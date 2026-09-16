rule _XCR_v013_
{
	meta:
		description = "XCR v0.13"
	strings:
		$0 = {E8 5D 8B CD 81 ED 7A 29 40 89 AD 0F 6D}
	condition:
		$0 at entrypoint
}