rule TTP_XOR_QUAD_CurrentVersionRun_bfa2 {
  strings:
    $key_bfa2 = { ec cd [2] c8 c3 [2] e3 ef [2] cd cd [2] d9 d6 [2] d6 cc [2] c8 d1 [2] ca d0 [2] d1 d6 [2] cd d1 [2] d1 fe }

  condition:
    any of them
}