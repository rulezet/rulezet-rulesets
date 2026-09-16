rule Win_Trojan_Hupigon_518
{
strings:
	$a0 = { 3ea07ea011c647809e9f3bcdb38ead3d423a247ec44efb1d7066ccb9d4b27ecf8edfb595967acc6319ebce2e9e65386a2ad94e9447402a42032f6fb42bdc97c51341da57f4ba84ccf247c9afdd59 }


condition:
	$a0
}