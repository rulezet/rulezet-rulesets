rule Win_Trojan_XRes_2
{
strings:
	$a0 = { 014181e2f0ff8bf18bfab80042cd21b440bae001b98e0190cd218bc68bdf03d8b104d3cb }


condition:
	$a0
}