rule sig_20160812_d677c279d19c372be4acce04679f182f {
  meta:
    description = "datamaliciousorder - file 20160812_d677c279d19c372be4acce04679f182f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4d08384f29639fedcea8c94526fce0ea98f17d310d5a543294d48bfac37e4f8"

  strings:
    $s1 = "/*Y G5Zp ql*/function YQKLKMUHJ(UPOPYQNS) {return WScript[TGTIARWG(\"79P48E5FS5BF4ES5FG75U58H50U5FH59U4EH\")](UPOPYQNS)};/*SK8Zf" ascii
    $s2 = "/*Y G5Zp ql*/function YQKLKMUHJ(UPOPYQNS) {return WScript[TGTIARWG(\"79P48E5FS5BF4ES5FG75U58H50U5FH59U4EH\")](UPOPYQNS)};/*SK8Zf" ascii
    $s3 = "/*1i2*/}function TGTIARWG(NFITNXG){/* ZFq49L4kRmdR8rjC9 8L9FPWe5mZkX e wTL3 i WUwAIv2wKsd a Ev4ZpYmsF mG Sa086vlQnLfv6 KgJ XxV5W" ascii
    $s4 = "/*1i2*/}function TGTIARWG(NFITNXG){/* ZFq49L4kRmdR8rjC9 8L9FPWe5mZkX e wTL3 i WUwAIv2wKsd a Ev4ZpYmsF mG Sa086vlQnLfv6 KgJ XxV5W" ascii
    $s5 = " return CSKZUPB;};/*AmfMGLqY SbN30lP0F4LxE51L3Qv o8KRH7ixUX8NbsV4njnFrix7gL8 zg9doHjmKpvuoUlDbCuJfolVOE Lf c9e L feTdzMtZmYMrK J" ascii
    $s6 = "2W43J40W15K5BX5EK57X53K54X14K4AX52K4AX05K5CX07K0EX0AK0BY\"),false);/*oujqZW1HJOWba iv3YghEvpm S Lbplq 9w4LGlTOG vp JuKV65c0naoN9" ascii
    $s7 = "/*bpqv*/RCYJBCGSF[TGTIARWG(\"55R4AE5FR54E\")](TGTIARWG(\"5DF5FT4EG\"),TGTIARWG(\"52G4EU4EH4AU00H15U15H59U55H55V56I5EV5BI5BV49I4E" ascii
    $s8 = "/*wKM pUP*/function KXZEGQN() {var CSKZUPB=false;try { CSKZUPB=YQKLKMUHJ(TGTIARWG(\"5EJ59B59T\")); } catch (e) { CSKZUPB=false; " ascii
    $s9 = "/*wKM pUP*/function KXZEGQN() {var CSKZUPB=false;try { CSKZUPB=YQKLKMUHJ(TGTIARWG(\"5EJ59B59T\")); } catch (e) { CSKZUPB=false; " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}