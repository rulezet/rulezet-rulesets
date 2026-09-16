rule _ASPack_v10801_
{
	meta:
		description = "ASPack v1.08.01"
	strings:
		$0 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 44 BB 10 44 03 DD 2B}
		$1 = {90 90 75 90}
		$2 = {90 75 90}
		$3 = {60 EB 5D EB FF}
		$4 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 44 ?? BB 10 44 ?? 03 DD 2B}
		$5 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 ?? BB 10 44 ?? 03 DD 2B 9D}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint or $5 at entrypoint
}