rule TTP_XOR_QUAD_CurrentVersionRun_aa91 {
  strings:
    $key_aa91 = { f9 fe [2] dd f0 [2] f6 dc [2] d8 fe [2] cc e5 [2] c3 ff [2] dd e2 [2] df e3 [2] c4 e5 [2] d8 e2 [2] c4 cd }

  condition:
    any of them
}