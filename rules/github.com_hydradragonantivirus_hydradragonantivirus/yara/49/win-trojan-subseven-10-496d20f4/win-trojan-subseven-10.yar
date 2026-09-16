rule Win_Trojan_SubSeven_10
{
strings:
	$a0 = { f3b52f16fc34eedff5104847ad59fc62f21aaa9a94bffc2bfb6afc6b17f16c028f71b32ca6801e57aeabc0808fa2ad76aa9ed64396939cb208a4a8e257fc4cdc73a5fce587b1ccdb852ffc48f9ad5cfc }


condition:
	$a0
}