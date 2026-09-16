rule TTP_XOR_QUAD_CurrentVersionRun_3828 {
  strings:
    $key_3828 = { 6b 47 [2] 4f 49 [2] 64 65 [2] 4a 47 [2] 5e 5c [2] 51 46 [2] 4f 5b [2] 4d 5a [2] 56 5c [2] 4a 5b [2] 56 74 }

  condition:
    any of them
}