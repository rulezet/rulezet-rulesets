rule sig_20150909_84c374059b03ad21b9b31b3edbe54c1f {
  meta:
    description = "datamaliciousorder - file 20150909_84c374059b03ad21b9b31b3edbe54c1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79c1485abe86fa2012bba4bddc2260e5a1c9983e54df20afc42ffc8876768914"

  strings:
    $x1  = "var gDebug=false;var gDebugOnMobile=false;var gNumDebugMessagesSent=0;var gNumDebugMessagesQueued=0;var gDebugMessageQueue=new A" ascii
    $s2  = "DumpLineNumber=0;debugMessageAlways(a,\"------------------ S T A R T   O F   D O M   D U M P --- Context: \"+b);debugRecursively" ascii
    $s3  = "i;gNumDebugMessagesQueued++;if(gNumDebugMessagesQueued==1){debugCheckMessageQueue()}}else{if(window.console){window.console.log(" ascii
    $s4  = "1);var a='/debugMessage.rhtml?message=\"'+b+'\"';new Ajax.Request(a,{method:\"get\",onSuccess:function(c){debugMessageWasSent(c)" ascii
    $s5  = "a){if(a){a.stop()}}var debugDomDumpLineNumber=0;function debugDumpDomFrom(c,b){var a=kDebugFunction+\"_debugDumpDomFrom\";debugD" ascii
    $s6  = "ways(e,\"-\"+(debugDomDumpLineNumber++)+g+\"<\"+a+\" id='\"+b+\"'>\");var c;for(c=0;c<d.childNodes.length;c++){var f=d.childNode" ascii
    $s7  = "mpDomFrom(c,\"\");debugMessageAlways(a,\"------------------ E N D   O F   D O M   D U M P\")}function debugRecursivelyDumpDomFro" ascii
    $s8  = "null){var b=new Date();var a=b-this.startTime;debugMessageAlways(this.id,\"Stop - Elapsed Time: \"+a)}}});function debugStopTime" ascii
    $s9  = "g){var e=kDebugFunction+\"_recursivelyDumpDomFrom\";var b=d.id;var a=d.nodeName.toLowerCase();if(a==\"#text\"){return}debugMessa" ascii
    $s10 = "ursivelyDumpDomFrom(f,g+\"   \")}if(a==\"img\"){return}debugMessageAlways(e,\"-\"+(debugDomDumpLineNumber++)+g+\"</\"+a+\">\")};" ascii
    $s11 = "Failure:function(c){debugMessageWasNotSent(c)}})}function debugMessageWasSent(a){debugCheckMessageQueue()}function debugMessageW" ascii
    $s12 = "r_JumpToScene=kDebugTimer+\"_!jumpToScene\";var kDebugTimer_DisplayScene=kDebugTimer+\"_!displayScene\";function debugWarning(a," ascii
    $s13 = "c+g)}}}function debugSendNextMessageInQueue(){var b=gDebugMessageQueue[0];gNumDebugMessagesQueued--;gDebugMessageQueue.splice(0," ascii
    $s14 = "tion debugMessage(a,b){if(gDebug==false){return}if((gDevice==kDeviceMobile)&&(gDebugOnMobile==false)){return}debugSendMessage(a," ascii
    $s15 = "this.id=a;this.startTime=new Date();debugMessageAlways(a,\"Start\")}else{this.startTime=null}},stop:function(){if(this.startTime" ascii
    $s16 = "asNotSent(a){debugCheckMessageQueue()}function debugCheckMessageQueue(){if(gNumDebugMessagesQueued>0){setTimeout(debugSendNextMe" ascii
    $s17 = "f(gDebug===false){return}debugSendMessage(a,\"WARNING: \"+b,true)}function debugMessageAlways(a,b){debugSendMessage(a,b,true)}fu" ascii
    $s18 = "b,false)}function debugSendMessage(b,g,a){var e=b.indexOf(\"_\");var d=b.substring(0,e);var h=b.substring(e+1);var f=false;if(d[" ascii
    $s19 = "ssageInQueue,10)}}var DebugTimer=Class.create({initialize:function(a){var b=a.indexOf(\"_\");var c=a.substring(b+1);if(c[0]!=\"!" ascii
    $s20 = "}else{if(d==kDebugFunction){c=h+\"() \"}else{c=d+\".\"+h+\"() \"}}}else{c=\"\"}gDebugLastClassName=d;gDebugLastMethodName=h;if(g" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}