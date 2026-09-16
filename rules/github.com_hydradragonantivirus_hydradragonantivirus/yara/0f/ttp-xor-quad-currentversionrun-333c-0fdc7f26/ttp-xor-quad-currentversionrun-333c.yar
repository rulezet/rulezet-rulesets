rule TTP_XOR_QUAD_CurrentVersionRun_333c {
  strings:
    $key_333c = { 60 53 [2] 44 5d [2] 6f 71 [2] 41 53 [2] 55 48 [2] 5a 52 [2] 44 4f [2] 46 4e [2] 5d 48 [2] 41 4f [2] 5d 60 }

  condition:
    any of them
}