rule sig_20170407_dd1a8a2f582254c152a1e68bbc0c7358 {
  meta:
    description = "datamaliciousorder - file 20170407_dd1a8a2f582254c152a1e68bbc0c7358.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8053ab96ad2790f92bb8155f15a0a7b6b812ee11e6a08b788b9fe1b9b6589b45"

  strings:
    $s1 = "var rima = 500;" fullword ascii
    $s2 = "function ataaa(ziyter) {eval(ziyter);}" fullword ascii
    $s3 = "var jamie = new Array('/','t',\"\",\":\",'p','h','S','a',\"T\",'');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}