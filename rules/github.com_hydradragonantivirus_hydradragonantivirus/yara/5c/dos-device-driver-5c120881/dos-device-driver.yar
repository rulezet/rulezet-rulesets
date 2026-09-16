rule _DOS_Device_Driver_
{
	meta:
		description = "DOS Device Driver"
	strings:
		$0 = {FF FF FF FF}
	condition:
		$0 at entrypoint
}