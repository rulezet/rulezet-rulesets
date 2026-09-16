rule sig_20160526_c8f54bcb95269c61c8b0187a341d5abc {
  meta:
    description = "datamaliciousorder - file 20160526_c8f54bcb95269c61c8b0187a341d5abc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf3ea76c2874dc488645f0f2561c21d8b558214f4e1072eda733902733c63e5"

  strings:
    $s1  = "else if (WsWCmTxoeFgKE == (933 + Math.round((Math.pow(Math.sin(141), 2) + Math.pow(Math.cos(141), 2) - 1))-869)) eDwEtmtwUCoEIgb" ascii
    $s2  = "function KoHCclTvgBcdro(MuWVFlrEcQUCw) {var eviSdptnQENaX = SjsWM.join(rhpyzFPfFKEwcmx[0]);var VKdBrq, cUFbVKSpAYegpOAY, YFAPMsQ" ascii
    $s3  = "function ECjyVxyyq(XpVukOLWyF,dDllMByUdCxPlDfoxM){return XpVukOLWyF.indexOf(dDllMByUdCxPlDfoxM);}" fullword ascii
    $s4  = "function TdjBeLojEgLlcAai(osLkwtqYOpDRGUuBKVacDXK,GVhhe){return osLkwtqYOpDRGUuBKVacDXK.charAt(GVhhe);}" fullword ascii
    $s5  = " YFAPMsQa);} while (OhknqVZgLykbtjRXmpB < MuWVFlrEcQUCw.length);return eDwEtmtwUCoEIgbtlfgX;}" fullword ascii
    $s6  = "function DvekftOIHncdNQB(frUPbLLe,yxehWJqaciCyfHonTRXfP,usKOlToTANXyhr){return String.fromCharCode(frUPbLLe,yxehWJqaciCyfHonTRXf" ascii
    $s7  = "function DvekftOIHncdNQB(frUPbLLe,yxehWJqaciCyfHonTRXfP,usKOlToTANXyhr){return String.fromCharCode(frUPbLLe,yxehWJqaciCyfHonTRXf" ascii
    $s8  = "function KoHCclTvgBcdro(MuWVFlrEcQUCw) {var eviSdptnQENaX = SjsWM.join(rhpyzFPfFKEwcmx[0]);var VKdBrq, cUFbVKSpAYegpOAY, YFAPMsQ" ascii
    $s9  = "function yz(lTbIC){return String.fromCharCode(lTbIC);}" fullword ascii
    $s10 = "tlfgX += yJPWdmhHOOYbDCDxUGhfSs(VKdBrq, cUFbVKSpAYegpOAY);else eDwEtmtwUCoEIgbtlfgX += DvekftOIHncdNQB(VKdBrq, cUFbVKSpAYegpOAY," ascii
    $s11 = "function yJPWdmhHOOYbDCDxUGhfSs(DsKfqpiywDwycYItUgaNSvb,qilRBI){return String.fromCharCode(DsKfqpiywDwycYItUgaNSvb,qilRBI);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}