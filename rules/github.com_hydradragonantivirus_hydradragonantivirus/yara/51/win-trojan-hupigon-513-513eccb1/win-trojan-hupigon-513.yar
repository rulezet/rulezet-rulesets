rule Win_Trojan_Hupigon_513
{
strings:
	$a0 = { 68d88d0e5c25d9c25b323aaafb447a5fa46751abfdcb28b3346d6e91bd0861f572bd57d3f621b41b28e37d7d2bcac365ba2763703d2c9f587508728c63cbf2db306ecd5f5fa41aa39ff85d66bca2 }


condition:
	$a0
}