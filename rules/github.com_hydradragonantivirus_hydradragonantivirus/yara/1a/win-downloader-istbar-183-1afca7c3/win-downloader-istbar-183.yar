rule Win_Downloader_Istbar_183
{
strings:
	$a0 = { ff2538204000ff253c204000ff2594204000cccccccccccccccccccc568bf1e801000856f64424080174 }

	$a1 = { 666361304956662e657865002f6169643a }


condition:
	$a0 and $a1
}