rule Win_Trojan_Spanska_II_1
{
strings:
	$a0 = { 74f8bfc97cf8ebd2ccfe74173c6f6fd424f423b417ffffb4c97ed0c8fec974d0c97ef8b9fe3c6f17 }


condition:
	$a0
}