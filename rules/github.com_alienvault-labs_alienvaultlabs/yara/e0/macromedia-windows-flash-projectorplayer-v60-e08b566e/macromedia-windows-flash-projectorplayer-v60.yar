rule _Macromedia_Windows_Flash_ProjectorPlayer_v60_
{
	meta:
		description = "Macromedia Windows Flash Projector/Player v6.0"
	strings:
		$0 = {E9}
	condition:
		$0 at entrypoint
}