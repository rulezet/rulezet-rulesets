rule Win_Trojan_Lifeform_1
{
strings:
	$a0 = { e804faf7dcf7dcfb8db62c008bfe5633c0bbed032e8135fd06cc40eb0490eb069083c702ebf83bc376eac3075697f9b94aa546a572f4b6d3e08de08cf2301f4539c7cbdc87062cc773f3ed9596de529543a251 }


condition:
	$a0
}