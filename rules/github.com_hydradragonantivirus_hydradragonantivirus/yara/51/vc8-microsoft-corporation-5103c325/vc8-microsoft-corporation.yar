rule _VC8__Microsoft_Corporation_
{
	meta:
		description = "VC8 -> Microsoft Corporation"
	strings:
		$0 = {E8 ?? ?? ?? ?? E9 ?? ?? FF FF}
	condition:
		$0 at entrypoint
}