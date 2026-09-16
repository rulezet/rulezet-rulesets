rule sig_20151209_a7adf63c44026233d638348ffd0d61ca {
  meta:
    description = "datamaliciousorder - file 20151209_a7adf63c44026233d638348ffd0d61ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76d3d8e2aa45603e11e8672c2f591391a48636a0e961fa0052ca6d1310c0bbcf"

  strings:
    $s1  = "function GqiSOTI(VtfDkYsaTFljmPvPKPLkIEXQzgpEdwxyUxrq) {return !isNaN(parseFloat(VtfDkYsaTFljmPvPKPLkIEXQzgpEdwxyUxrq)) && isFin" ascii
    $s2  = "function GqiSOTI(VtfDkYsaTFljmPvPKPLkIEXQzgpEdwxyUxrq) {return !isNaN(parseFloat(VtfDkYsaTFljmPvPKPLkIEXQzgpEdwxyUxrq)) && isFin" ascii
    $s3  = "bNwJNUO[QZWnRlkhmiy]=(-412+412)/842; while(true) { if(qYbNwJNUO[QZWnRlkhmiy] > KRmAB[QZWnRlkhmiy].length-(-105+931)/826) { break" ascii
    $s4  = "+;}} return adjWXgMLnVT}" fullword ascii
    $s5  = "function opoII(iqWuxbspiEb,qMAznMnNfKOrM,IqNNoAkJ){jUqp=parseInt(iqWuxbspiEb,qMAznMnNfKOrM);EkpbN=jUqp.toString(IqNNoAkJ);return" ascii
    $s6  = " EkpbN;}function PRKTtzcVaHZswGQ(CKaaqEIvSFutIgjJh){eval(CKaaqEIvSFutIgjJh)}" fullword ascii
    $s7  = "function VSxELuTNROZpOhrnRKnIGwMQhNaXyJbIMGdfvEdHJsTtIPIxOhHkIg(tHRcRGfStdaqg,DRzkTbFmbgSnpl){ return rOBzg[opoII(tHRcRGfStdaqg[" ascii
    $s8  = "function VLvMGlyiPDdKdSynm(KRmAB){adjWXgMLnVT= '';for(QZWnRlkhmiy=(-832+832)/50; QZWnRlkhmiy < (465+391)/428; QZWnRlkhmiy++) {qY" ascii
    $s9  = "function VSxELuTNROZpOhrnRKnIGwMQhNaXyJbIMGdfvEdHJsTtIPIxOhHkIg(tHRcRGfStdaqg,DRzkTbFmbgSnpl){ return rOBzg[opoII(tHRcRGfStdaqg[" ascii
    $s10 = "function CNIKplgKhGA(aYTqcclQ,UEfrDT){return aYTqcclQ.split(UEfrDT)}" fullword ascii
    $s11 = "function opoII(iqWuxbspiEb,qMAznMnNfKOrM,IqNNoAkJ){jUqp=parseInt(iqWuxbspiEb,qMAznMnNfKOrM);EkpbN=jUqp.toString(IqNNoAkJ);return" ascii
    $s12 = "function VLvMGlyiPDdKdSynm(KRmAB){adjWXgMLnVT= '';for(QZWnRlkhmiy=(-832+832)/50; QZWnRlkhmiy < (465+391)/428; QZWnRlkhmiy++) {qY" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}