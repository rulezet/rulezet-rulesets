rule emotet4_basic: trojan
{
meta:
author = "psrok1/mak"
module = "emotet"
strings:
$emotet4_rsa_public = { 8d ?? ?? 5? 8d ?? ?? 5? 6a 00 68 00 80 00 00 ff 35 [4] ff 35 [4] 6a 13 68 01 00 01 00 ff 15 [4] 85 }
$emotet4_cnc_list = { 39 ?? ?5 [4] 0f 44 ?? (FF | A3)}
condition:
all of them
}