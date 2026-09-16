rule TTP_XOR_QUAD_CurrentVersionRun_38ff {
  strings:
    $key_38ff = { 6b 90 [2] 4f 9e [2] 64 b2 [2] 4a 90 [2] 5e 8b [2] 51 91 [2] 4f 8c [2] 4d 8d [2] 56 8b [2] 4a 8c [2] 56 a3 }

  condition:
    any of them
}