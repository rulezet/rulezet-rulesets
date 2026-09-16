rule Win_Trojan_Kolweb_9
{
strings:
	$a0 = { 55681fd3410064ff30648920b8f4184200ba5cd34100e8906dfeffb8f8184200ba8cd34100e8816dfeff8b55fcb8bcd34100e8a472feff85c07e0f8d45fcbac8d34100e8b36ffeffeb }


condition:
	$a0
}