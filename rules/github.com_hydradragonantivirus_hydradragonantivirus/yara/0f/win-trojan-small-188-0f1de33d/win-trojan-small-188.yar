rule Win_Trojan_Small_188
{
strings:
	$a0 = { cd21b82135cd21895c428c4444b425ba1801cd2192cd2740750b5f568bfebe4201b5fef3a448601e80fc4075118bf2 }


condition:
	$a0
}