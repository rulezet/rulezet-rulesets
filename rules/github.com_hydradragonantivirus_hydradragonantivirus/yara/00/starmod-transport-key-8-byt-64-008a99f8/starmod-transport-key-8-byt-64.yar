rule STARMOD_transport_key__8_byt_64_
{
strings:
	$a0 = { a26fa6a2f85e838dbe6234c1cbf72fbfbd9473efbc46d6b4db243139de0c68498a67d5fd2a6d3a702ae4dcd10787d5310e270c456a281ae12293c7d0d5f6ef6d }

condition:
	$a0
}