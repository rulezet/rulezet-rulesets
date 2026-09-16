rule hc_fallchill__hiddencobra__xor_ip : malware windows apt
{
  meta:
    description = "hidden cobra: XOR used for IP"
  strings:
    $s0 = { 53 3a 9c 57 }
    $s1 = { 57 9c 3a 53 }
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550)
    and any of them
}