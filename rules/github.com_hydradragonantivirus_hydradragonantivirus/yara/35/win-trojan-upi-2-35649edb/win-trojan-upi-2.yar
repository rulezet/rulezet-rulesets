rule Win_Trojan_UPI_2
{
strings:
	$a0 = { bc005589e581ec0203c606092500b01b50bf9c251e579a6f018e00b02450bfa0251e579a6f018e00b01b50bf64 }


condition:
	$a0
}