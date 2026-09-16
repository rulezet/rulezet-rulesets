rule Win_Trojan_Hupigon_536
{
strings:
	$a0 = { 7f566b625bcb9ad7c77172468aed17fd16e953a39050d1d3773a5a70282193fd4cdace82320fffe98aa9f1c68ee4cb89bb050a6bfc1ffbe15f9a08971f06262bae92373243a867e5057ad03ec16d }


condition:
	$a0
}