rule Win_Trojan_Vpp_3
{
strings:
	$a0 = { e89bff5a582bc22d0300c645ffe88bd74aabb440b90300cd21e87effb94d01b4408d56f0cd21 }


condition:
	$a0
}