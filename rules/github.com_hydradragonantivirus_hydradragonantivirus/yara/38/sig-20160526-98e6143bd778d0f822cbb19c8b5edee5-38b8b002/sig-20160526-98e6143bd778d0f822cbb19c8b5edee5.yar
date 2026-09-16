rule sig_20160526_98e6143bd778d0f822cbb19c8b5edee5 {
  meta:
    description = "datamaliciousorder - file 20160526_98e6143bd778d0f822cbb19c8b5edee5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31edf09c655171acc8e2550621ffde4e58188724c38ddb25d7817cf45ce1103f"

  strings:
    $s1  = "nd((Math.pow(Math.sin(138), 2) + Math.pow(Math.cos(138), 2) - 1))-998)) OiRogwCqWaiZoLRdAadcRa += iO(XydvEczkNrBmku);else if (ve" ascii
    $s2  = "function BNTrkAMoWzxAur(KLycKJIoOdpPP) {var llPtjDctY = VDPcDpoDVRFBbgXfnp.join(LVZeYPHXEgCpOZthQMQnxiqG[0]);var XydvEczkNrBmku," ascii
    $s3  = "function XAgIgIYlShJ(lgtmsYWmplQrnXYWT,RwUnQ){return lgtmsYWmplQrnXYWT.charAt(RwUnQ);}" fullword ascii
    $s4  = "bHxgyhrgqQ);} while (kJJkhtQQzto < KLycKJIoOdpPP.length);return OiRogwCqWaiZoLRdAadcRa;}" fullword ascii
    $s5  = "function XFcecdbWoIZnd(VqlceuQpKylu,keihX,aiZtvXjraeRrEbPjSox){return String.fromCharCode(VqlceuQpKylu,keihX,aiZtvXjraeRrEbPjSox" ascii
    $s6  = "function SJJHXkJSzUdkteNYzoSx(ZAWyufsMVn,gAZwjGQNIZHKriYgfd){return String.fromCharCode(ZAWyufsMVn,gAZwjGQNIZHKriYgfd);}" fullword ascii
    $s7  = "function iO(bDWyKUfLDioflynsgpaRJoma){return String.fromCharCode(bDWyKUfLDioflynsgpaRJoma);}" fullword ascii
    $s8  = "function BNTrkAMoWzxAur(KLycKJIoOdpPP) {var llPtjDctY = VDPcDpoDVRFBbgXfnp.join(LVZeYPHXEgCpOZthQMQnxiqG[0]);var XydvEczkNrBmku," ascii
    $s9  = "JHXkJSzUdkteNYzoSx(XydvEczkNrBmku, EXgpCBGJxc);else OiRogwCqWaiZoLRdAadcRa += XFcecdbWoIZnd(XydvEczkNrBmku, EXgpCBGJxc, nesGXfpm" ascii
    $s10 = "function XFcecdbWoIZnd(VqlceuQpKylu,keihX,aiZtvXjraeRrEbPjSox){return String.fromCharCode(VqlceuQpKylu,keihX,aiZtvXjraeRrEbPjSox" ascii
    $s11 = "function ZPysMsG(AUhORhuC,OHnRpmUlgAyktJRjRpX){return AUhORhuC.indexOf(OHnRpmUlgAyktJRjRpX);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}