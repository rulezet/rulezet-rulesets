rule TTP_XOR_QUAD_CurrentVersionRun_233c {
  strings:
    $key_233c = { 70 53 [2] 54 5d [2] 7f 71 [2] 51 53 [2] 45 48 [2] 4a 52 [2] 54 4f [2] 56 4e [2] 4d 48 [2] 51 4f [2] 4d 60 }

  condition:
    any of them
}