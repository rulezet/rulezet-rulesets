import "pe"
rule _Microsoft_Visual_C__Basic_NET_
{
	meta:
		description = "Microsoft Visual C# / Basic .NET"
	strings:
		$0 = {01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B}
		$1 = {FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}