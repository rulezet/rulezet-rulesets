rule DebuggerTiming__PerformanceCounter: AntiDebug DebuggerTiming {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = "QueryPerformanceCounter"

  condition:
    any of them
}