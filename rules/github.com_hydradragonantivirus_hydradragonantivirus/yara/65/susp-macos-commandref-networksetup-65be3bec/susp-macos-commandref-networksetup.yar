rule SUSP_MacOS_CommandRef_networksetup {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-23"
    version     = "1.0"
    description = "check for references to networksetup utility"

  strings:
    $ = "networksetup" ascii wide

  condition:
    all of them
}