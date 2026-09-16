rule sig_20160526_648434dae028dfc2e8798e970fba65cb {
  meta:
    description = "datamaliciousorder - file 20160526_648434dae028dfc2e8798e970fba65cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cbfce9493bf616ccf4e6ef2477b5716414d9875d8b1642601f658133d53e96c"

  strings:
    $s1  = "ow(Math.sin(642), 2) + Math.pow(Math.cos(642), 2) - 1))-863)) muVmwDEmnIsGDUxzx += kc(FVFkkwLvhxowbskMQKGlYaZy);else if (XYHpnvv" ascii
    $s2  = "(607), 2) + Math.pow(Math.cos(607), 2) - 1))-32) & 0xff;uZOuHdBnwkaEeuYntMKybZlj = IGiBUXFvI>> (199 + Math.round((Math.pow(Math." ascii
    $s3  = "function ifjlP(FScJKWBUxoPNR) {var RxpgRcxFBpuBofUQQ = eXiVGwWqkNWw.join(mToNNqXIOCH[0]);var FVFkkwLvhxowbskMQKGlYaZy, uZOuHdBnw" ascii
    $s4  = "function qurrjs(keKnwXZIf,HjMjaKGWV){return keKnwXZIf.charAt(HjMjaKGWV);}" fullword ascii
    $s5  = "function VazepRCqjdigWdrQp(qbCEpseeCkJiy,SPAMNfkikuVSZEIoBqgu){return qbCEpseeCkJiy.indexOf(SPAMNfkikuVSZEIoBqgu);}" fullword ascii
    $s6  = "function kc(groXVJPT){return String.fromCharCode(groXVJPT);}" fullword ascii
    $s7  = "function rHTfOzngyyjyvzetHhlq(zjJljkyMbSteoxueOkz,kvcFyljEy){return String.fromCharCode(zjJljkyMbSteoxueOkz,kvcFyljEy);}" fullword ascii
    $s8  = "HTfOzngyyjyvzetHhlq(FVFkkwLvhxowbskMQKGlYaZy, uZOuHdBnwkaEeuYntMKybZlj);else muVmwDEmnIsGDUxzx += wXbikjELPOwWEZd(FVFkkwLvhxowbs" ascii
    $s9  = "function ifjlP(FScJKWBUxoPNR) {var RxpgRcxFBpuBofUQQ = eXiVGwWqkNWw.join(mToNNqXIOCH[0]);var FVFkkwLvhxowbskMQKGlYaZy, uZOuHdBnw" ascii
    $s10 = "function wXbikjELPOwWEZd(KLasdcZUKjBTTFqllaiWJq,gGaiP,ZfGicVhQOtCJlzex){return String.fromCharCode(KLasdcZUKjBTTFqllaiWJq,gGaiP," ascii
    $s11 = "function wXbikjELPOwWEZd(KLasdcZUKjBTTFqllaiWJq,gGaiP,ZfGicVhQOtCJlzex){return String.fromCharCode(KLasdcZUKjBTTFqllaiWJq,gGaiP," ascii
    $s12 = "kMQKGlYaZy, uZOuHdBnwkaEeuYntMKybZlj, KkTPPoWLQQV);} while (YZkikwrZUFmMcGmllHg < FScJKWBUxoPNR.length);return muVmwDEmnIsGDUxzx" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}