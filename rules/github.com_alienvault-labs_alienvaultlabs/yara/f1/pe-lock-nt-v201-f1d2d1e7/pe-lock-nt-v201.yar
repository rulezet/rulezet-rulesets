rule _PE_Lock_NT_v201_
{
	meta:
		description = "PE Lock NT v2.01"
	strings:
		$0 = {EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02}
	condition:
		$0 at entrypoint
}