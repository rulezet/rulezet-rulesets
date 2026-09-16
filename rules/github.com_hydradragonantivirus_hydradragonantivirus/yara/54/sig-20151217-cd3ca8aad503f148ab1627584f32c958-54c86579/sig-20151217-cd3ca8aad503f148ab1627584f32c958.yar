rule sig_20151217_cd3ca8aad503f148ab1627584f32c958 {
  meta:
    description = "datamaliciousorder - file 20151217_cd3ca8aad503f148ab1627584f32c958.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f495985059985aa304bc3ee1ee55ad20a80772e442c774da688b6b75bc36891a"

  strings:
    $s1  = ") - 1));while(true){if (HrYefddAqRu >= (5268+684)/992){break;}cIbYqpstF[HrYefddAqRu]=Math.round((Math.pow(Math.sin(723), 2) + Ma" ascii
    $s2  = "ow(Math.cos(681), 2) - 1)));} cIbYqpstF[HrYefddAqRu]++;}HrYefddAqRu++;} return ofiBizmSQIq}" fullword ascii
    $s3  = "th.pow(Math.cos(723), 2) - 1)); while(true) { if(cIbYqpstF[HrYefddAqRu] > EvzVs[HrYefddAqRu].length-(-248+278)/30) { break; } if" ascii
    $s4  = "function kiIOoQQJaKZZVvdOs(EvzVs){ofiBizmSQIq= '';HrYefddAqRu=Math.round((Math.pow(Math.sin(594), 2) + Math.pow(Math.cos(594), 2" ascii
    $s5  = "function kiIOoQQJaKZZVvdOs(EvzVs){ofiBizmSQIq= '';HrYefddAqRu=Math.round((Math.pow(Math.sin(594), 2) + Math.pow(Math.cos(594), 2" ascii
    $s6  = "function BASfIkQlOGqSKVMQb(rnbcmJufKz,uUFhiAMwtn) {return parseInt(rnbcmJufKz,uUFhiAMwtn);}" fullword ascii
    $s7  = "function Mnbjc(iVpuDMliZtE,yAGYIFLerYUSf,iJARaNsu){ytNU=BASfIkQlOGqSKVMQb(iVpuDMliZtE,yAGYIFLerYUSf);zBkQM=ytNU.toString(iJARaNs" ascii
    $s8  = "function Mnbjc(iVpuDMliZtE,yAGYIFLerYUSf,iJARaNsu){ytNU=BASfIkQlOGqSKVMQb(iVpuDMliZtE,yAGYIFLerYUSf);zBkQM=ytNU.toString(iJARaNs" ascii
    $s9  = "function sazBTzo(QfMPhNrdLYwvPEyIbdkCrPiaaPabgnCvUhwC) {return !bHtIQpqTFmi(yzcStIwdBPHRzBB(QfMPhNrdLYwvPEyIbdkCrPiaaPabgnCvUhwC" ascii
    $s10 = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s11 = "function mCQkvjXAdCvNMdvxEBThnOoqouMlkvrvbPXnCSNYsBwFWqtZBjSQuD(ECpFGHNtEZAHg,OPioexsBjGKomW){ return UfwEOhB[xfRNgqxT[Mnbjc(ECp" ascii
    $s12 = "function MHteyOhvYJwflsy(qyqXevdUUgWkyUKMr,lPerXAOeSaOoldwnIFumfHrgNvKLXPFfWh,maVvJJccZdyFentvQReXPmdATuzOcCjQoBN){eval(qyqXevdU" ascii
    $s13 = "function MHteyOhvYJwflsy(qyqXevdUUgWkyUKMr,lPerXAOeSaOoldwnIFumfHrgNvKLXPFfWh,maVvJJccZdyFentvQReXPmdATuzOcCjQoBN){eval(qyqXevdU" ascii
    $s14 = "function yzcStIwdBPHRzBB(tSTCdDMZMclQslusOpx) {return parseFloat(tSTCdDMZMclQslusOpx);}" fullword ascii
    $s15 = "function R(hracDbqQpawMtj,FRAibVTJqdUCL,UOATEzWgvFm) {hracDbqQpawMtj[FRAibVTJqdUCL]=UOATEzWgvFm;}" fullword ascii
    $s16 = "function WqrKSBAjVGDO(QvPoAfoMFZjFz) {return isFinite(QvPoAfoMFZjFz);}" fullword ascii
    $s17 = "function bHtIQpqTFmi(RnefZzQYLNTdTg) {return isNaN(RnefZzQYLNTdTg);}" fullword ascii
    $s18 = ",'V','.','T','Y','e','h','W','K','o','o','*','Q','X',']','a','[','Y','_','H','Z','F',' ','s','J','S','.','[',')','t','I',String." ascii
    $s19 = "u);return zBkQM;}" fullword ascii
    $s20 = "function mCQkvjXAdCvNMdvxEBThnOoqouMlkvrvbPXnCSNYsBwFWqtZBjSQuD(ECpFGHNtEZAHg,OPioexsBjGKomW){ return UfwEOhB[xfRNgqxT[Mnbjc(ECp" ascii

  condition:
    uint16(0) == 0x6678 and
    8 of them
}