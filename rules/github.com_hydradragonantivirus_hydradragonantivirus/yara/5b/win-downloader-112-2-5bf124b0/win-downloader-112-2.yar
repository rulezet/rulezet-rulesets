rule Win_Downloader_112_2
{
strings:
	$a0 = { 52adfcc3542309726b950db35532bde71175426f57adfd72e0f2f9d2b308c636ab38e9f441ee0673550053ca8888b6aa57adfda5153bba344cadfcfbf26df37255a1a8fecab586d04d14a81de1f209ae4837 }


condition:
	$a0
}