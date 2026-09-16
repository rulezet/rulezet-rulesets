rule Win_Trojan_IRCBot_188
{
strings:
	$a0 = { 2d453ef11250494e47534f7203ba53cd04ffffffff732d2fb926dc2780fcdffb24055b554450bb4a606b057d273f4aa2004bf9c429fa37f8ffd86b5052654f76 }


condition:
	$a0
}