rule sig_20160301_10f8b001218682491852831e32c14821 {
  meta:
    description = "datamaliciousorder - file 20160301_10f8b001218682491852831e32c14821.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c33a65a280ecd703433d1cf16c5543b474271bd253dc9f2caa957da868f07906"

  strings:
    $s1 = "illusionApproximation = operationLegal[(\"b\\u006f\\u0078i\\u006e\\u0067\", \"\\u0063\\u0061m\\u0065\\u0072\" + \"a\", \"\\u0074" ascii
    $s2 = "operationLegal = ((178, 1), this);" fullword ascii
    $s3 = "while(illusionApproximation[(\"\\u0062\" + \"\\u0061n\\u0064\" + \"\\u0061ge\", \"\\u0074\" + \"ax\", \"i\\u006e\\u0076\\u0065r" ascii
    $s4 = "\" + \"b\\u0073o\" + \"lu\\u0074e\", function String.prototype.almanacRecord() {" fullword ascii
    $s5 = "while(illusionApproximation[(\"\\u0062\" + \"\\u0061n\\u0064\" + \"\\u0061ge\", \"\\u0074\" + \"ax\", \"i\\u006e\\u0076\\u0065r" ascii
    $s6 = "} catch(exportRegent) {};" fullword ascii

  condition:
    uint16(0) == 0x706f and
    all of them
}