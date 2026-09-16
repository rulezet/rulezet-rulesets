rule TTP_XOR_QUAD_CurrentVersionRun_233d {
  strings:
    $key_233d = { 70 52 [2] 54 5c [2] 7f 70 [2] 51 52 [2] 45 49 [2] 4a 53 [2] 54 4e [2] 56 4f [2] 4d 49 [2] 51 4e [2] 4d 61 }

  condition:
    any of them
}