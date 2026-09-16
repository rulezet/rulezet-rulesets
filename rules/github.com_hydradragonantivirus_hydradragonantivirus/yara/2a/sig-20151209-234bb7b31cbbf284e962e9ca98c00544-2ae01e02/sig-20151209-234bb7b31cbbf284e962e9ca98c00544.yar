rule sig_20151209_234bb7b31cbbf284e962e9ca98c00544 {
  meta:
    description = "datamaliciousorder - file 20151209_234bb7b31cbbf284e962e9ca98c00544.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04649c428944a76a3d377cdf64b9e70d35b529ce3889c54e897775e4655b539d"

  strings:
    $s1  = "function VSXQzpo(LuZuGMfbtDtsYnPUAGnieydCDkhsKELiadLj) {return !isNaN(parseFloat(LuZuGMfbtDtsYnPUAGnieydCDkhsKELiadLj)) && isFin" ascii
    $s2  = "function VSXQzpo(LuZuGMfbtDtsYnPUAGnieydCDkhsKELiadLj) {return !isNaN(parseFloat(LuZuGMfbtDtsYnPUAGnieydCDkhsKELiadLj)) && isFin" ascii
    $s3  = "function DdjNRQHIABmtgkYQb(AlSFH){LpfQWtqGjDm= '';for(GRBEbIsSCFr=(-452+452)/754; GRBEbIsSCFr < (1983+5)/994; GRBEbIsSCFr++) {yD" ascii
    $s4  = "function mNvhXopxDPGwfHcneqAFuoDfWbftslXiUjwoEgQctJJMZTJNgxPabQ(RtRRudBfGrdRe,NpyLKZtXEGFJed){ return gyZFn[YNgVy(RtRRudBfGrdRe[" ascii
    $s5  = "function YNgVy(tdpmbSbATnf,IEmRxtNRyDRif,rYGpBLtG){gTzw=parseInt(tdpmbSbATnf,IEmRxtNRyDRif);pyEzF=gTzw.toString(rYGpBLtG);return" ascii
    $s6  = "function DdjNRQHIABmtgkYQb(AlSFH){LpfQWtqGjDm= '';for(GRBEbIsSCFr=(-452+452)/754; GRBEbIsSCFr < (1983+5)/994; GRBEbIsSCFr++) {yD" ascii
    $s7  = "function mNvhXopxDPGwfHcneqAFuoDfWbftslXiUjwoEgQctJJMZTJNgxPabQ(RtRRudBfGrdRe,NpyLKZtXEGFJed){ return gyZFn[YNgVy(RtRRudBfGrdRe[" ascii
    $s8  = "function htRoEKlEBUm(PxUOIAEg,YGZGem){return PxUOIAEg.split(YGZGem)}" fullword ascii
    $s9  = "}} return LpfQWtqGjDm}" fullword ascii
    $s10 = "vEwBJgD[GRBEbIsSCFr]=(-674+674)/306; while(true) { if(yDvEwBJgD[GRBEbIsSCFr] > AlSFH[GRBEbIsSCFr].length-(246+350)/596) { break;" ascii
    $s11 = "function YNgVy(tdpmbSbATnf,IEmRxtNRyDRif,rYGpBLtG){gTzw=parseInt(tdpmbSbATnf,IEmRxtNRyDRif);pyEzF=gTzw.toString(rYGpBLtG);return" ascii
    $s12 = " pyEzF;}function zJPiQTBsoEeimMY(uaZhzNXeDvNjcAWSv){eval(uaZhzNXeDvNjcAWSv)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}