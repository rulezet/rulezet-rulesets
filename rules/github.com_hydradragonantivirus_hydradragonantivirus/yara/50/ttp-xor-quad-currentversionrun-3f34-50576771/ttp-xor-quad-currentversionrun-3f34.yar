rule TTP_XOR_QUAD_CurrentVersionRun_3f34 {
  strings:
    $key_3f34 = { 6c 5b [2] 48 55 [2] 63 79 [2] 4d 5b [2] 59 40 [2] 56 5a [2] 48 47 [2] 4a 46 [2] 51 40 [2] 4d 47 [2] 51 68 }

  condition:
    any of them
}