rule trojan_ismrat_gen {
 meta:
 description = "ISM RAT"
 author = "Ahmed Zaki"
 reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/february/ism-rat/"
strings:
$s1 = "WinHTTP Example/1.0" wide
$s2 = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0" wide
$s3 = "|||Command executed successfully"
$dir = /Microsoft\\Windows\\Tmpe[a-z0-9]{2,8}/
condition:
uint16(0) == 0x5A4D and all of them
}