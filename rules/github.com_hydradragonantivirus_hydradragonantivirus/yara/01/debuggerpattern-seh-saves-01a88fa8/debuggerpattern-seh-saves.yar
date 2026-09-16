rule DebuggerPattern__SEH_Saves: AntiDebug DebuggerPattern {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = { 64 ff 35 00 00 00 00 }

  condition:
    any of them
}