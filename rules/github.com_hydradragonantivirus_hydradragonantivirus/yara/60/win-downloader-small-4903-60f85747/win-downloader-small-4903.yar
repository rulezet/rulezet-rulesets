rule Win_Downloader_Small_4903
{
strings:
	$a0 = { 6f7665dd14416d2f757031bb099e6e7314693bed1c016ac10568051040910a21 }


condition:
	$a0
}