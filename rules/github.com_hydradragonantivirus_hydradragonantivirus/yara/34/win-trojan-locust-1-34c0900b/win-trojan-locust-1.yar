rule Win_Trojan_Locust_1
{
strings:
	$a0 = { 0103d6b9b0058bddb440cd211fb8024233c933d28bddcd218bf08b3ef4003bfe722b7429b9f0 }


condition:
	$a0
}