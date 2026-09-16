import "hash"
rule IOC_NETSKY_zip {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NETSKY_LAB"
    date_IOC   = "2023-11-14 12:23:33"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NETSKY"
    file_type  = "zip"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "6f03ec60269a12b5067044a49f64c77108828bec971cacd120bf777d4c2b8fc0" or
    hash.sha256(0, filesize) == "58a6efaa90c5ee105e520c14c687f9ebefd733dd7d0f9eb599631b650804eb41" or
    hash.sha256(0, filesize) == "8bcd589ae4587480a36aaa7d1c610308f7915195dab6cfe95c106bf854c8e1f6" or
    hash.sha256(0, filesize) == "13b7d1449daae56c1d9e61b2b877a1f06cb1889eb2e7adb895a7af5695bf9eed" or
    hash.sha256(0, filesize) == "2daaafa914c24ec2d2191907e05d92738f5bd0da020bf7c696d1a7664273e175" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}