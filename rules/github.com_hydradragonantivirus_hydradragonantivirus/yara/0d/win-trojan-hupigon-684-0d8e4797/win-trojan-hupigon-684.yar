rule Win_Trojan_Hupigon_684
{
strings:
	$a0 = { d1a2071ead8ea21bf3ce0935ce3536c3a476c8d564ae0579e08787ec9ed6672e0d923b30416b09a80283cdb7b89374ebede2d3f052df5b0dab575fff98412827c4 }


condition:
	$a0
}