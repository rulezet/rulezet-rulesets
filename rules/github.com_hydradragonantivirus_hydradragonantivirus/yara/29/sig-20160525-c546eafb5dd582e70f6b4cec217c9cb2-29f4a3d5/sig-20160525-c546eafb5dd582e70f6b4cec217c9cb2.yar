rule sig_20160525_c546eafb5dd582e70f6b4cec217c9cb2 {
  meta:
    description = "datamaliciousorder - file 20160525_c546eafb5dd582e70f6b4cec217c9cb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33a636183cde3b2a087ec36f85a6a5cb41bd5444af1dd236c308d47ebc3cb92e"

  strings:
    $s1  = "function gZeeAlofU(jPAANLirSTGxs) {var GvfFzezGwQeRzBjUGUjZr = UXMMiQN.join(KDHQhZDFwJQiOjEhnDEgpF[0]);var USvHzJPaBzJtienoa, Fu" ascii
    $s2  = "PaBzJtienoa);else if (aIRrWZFP == (947 + Math.round((Math.pow(Math.sin(930), 2) + Math.pow(Math.cos(930), 2) - 1))-883)) QnkkEcY" ascii
    $s3  = "function qvLGYMbEPT(ZapGpYXyuMICZapNSZGEqySK,CqYvgeFqzFxcOdxGZvBpxsXE){return ZapGpYXyuMICZapNSZGEqySK.charAt(CqYvgeFqzFxcOdxGZv" ascii
    $s4  = "function qvLGYMbEPT(ZapGpYXyuMICZapNSZGEqySK,CqYvgeFqzFxcOdxGZvBpxsXE){return ZapGpYXyuMICZapNSZGEqySK.charAt(CqYvgeFqzFxcOdxGZv" ascii
    $s5  = "function UzfHGED(lAzYQOlSMBEGlFOc,EJyJypLWENGuBftWGMlXKNE){return lAzYQOlSMBEGlFOc.indexOf(EJyJypLWENGuBftWGMlXKNE);}" fullword ascii
    $s6  = "function NejvSFlrgGSTmwkQ(kzuIzxWiGGQpgHgZ,cyDJfkArjnxXfCsb,HJbzfocrHSTWUlSL){return String.fromCharCode(kzuIzxWiGGQpgHgZ,cyDJfk" ascii
    $s7  = "function QUCFpd(hjpfdVsqvWFN,RCTPOZqkT){return String.fromCharCode(hjpfdVsqvWFN,RCTPOZqkT);}" fullword ascii
    $s8  = "WJWjl += QUCFpd(USvHzJPaBzJtienoa, FujXmuCOeUgoqreIUqghGA);else QnkkEcYWJWjl += NejvSFlrgGSTmwkQ(USvHzJPaBzJtienoa, FujXmuCOeUgo" ascii
    $s9  = "qreIUqghGA, dYeizrQbQYYsAGhwAaT);} while (cjwqGWYKe < jPAANLirSTGxs.length);return QnkkEcYWJWjl;}" fullword ascii
    $s10 = "function gZeeAlofU(jPAANLirSTGxs) {var GvfFzezGwQeRzBjUGUjZr = UXMMiQN.join(KDHQhZDFwJQiOjEhnDEgpF[0]);var USvHzJPaBzJtienoa, Fu" ascii
    $s11 = "function k(ItpMqhQLlwqqNTJPeCVrMN){return String.fromCharCode(ItpMqhQLlwqqNTJPeCVrMN);}" fullword ascii
    $s12 = "function NejvSFlrgGSTmwkQ(kzuIzxWiGGQpgHgZ,cyDJfkArjnxXfCsb,HJbzfocrHSTWUlSL){return String.fromCharCode(kzuIzxWiGGQpgHgZ,cyDJfk" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}