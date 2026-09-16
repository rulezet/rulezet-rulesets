rule Win_Trojan_Companion_23
{
strings:
	$a0 = { b82135cd21bf5301891d8c4502ba1801b425cd218bd7cd273d004b753550061e078bfab02ef2ae57b84558abaa5f075850529c0ee81b00b8434fabb04daa5a58 }


condition:
	$a0
}