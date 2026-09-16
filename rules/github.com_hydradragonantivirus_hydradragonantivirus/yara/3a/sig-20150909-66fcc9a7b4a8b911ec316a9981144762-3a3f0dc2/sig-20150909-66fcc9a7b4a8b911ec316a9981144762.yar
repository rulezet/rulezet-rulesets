rule sig_20150909_66fcc9a7b4a8b911ec316a9981144762 {
  meta:
    description = "datamaliciousorder - file 20150909_66fcc9a7b4a8b911ec316a9981144762.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8cb219be59afdd8ca458fe43ef5602ac85c56de086956c2482035bb3073b2a9"

  strings:
    $x1  = "var kDeviceUnknown=\"deviceUnknown\";var kDeviceDesktop=\"deviceDesktop\";var kDeviceMobile=\"deviceMobile\";var kModeUnknown=\"" ascii
    $s2  = ",\"alert text to display when we timeout trying to download resources from iWork.com\");var kSlideLabel=CoreDocs.loc(\"Slide\"," ascii
    $s3  = "AgentString.lastIndexOf(\"Chrome/\")>0;if(Prototype.Browser.WebKit){browserPrefix=\"webkit\"}else{if(Prototype.Browser.Gecko){va" ascii
    $s4  = ", overriding device to be 'deviceMobile'\");gDevice=kDeviceMobile}if(navigator.userAgent.indexOf(\"modeDesktop\")!=-1){debugMess" ascii
    $s5  = "viceDesktop}if(navigator.userAgent.indexOf(\"deviceMobile\")!=-1){debugMessage(kDebugSetupShowController,\"Device was '\"+gDevic" ascii
    $s6  = "(kDebugSetupShowController,\"Mode was '\"+gMode+\"', overriding device to be 'modeDesktop'\");gMode=kModeDesktop}if(navigator.us" ascii
    $s7  = "he current slide number\");var kUnableToReachiWorkTryAgain=CoreDocs.loc(\"Slide couldn't be displayed.\\nDo you want to try agai" ascii
    $s8  = "plit(\":\");browserVersion=parseFloat(revisionIE[1])}else{if(revisionStringIE.lastIndexOf(\" \")>0){revisionIE=revisionStringIE." ascii
    $s9  = "ttachEvent(\"onload\",setupShowController)}else{if(window.addEventListener){window.addEventListener(\"load\",setupShowController" ascii
    $s10 = "ent.indexOf(\"modeMobile\")!=-1){debugMessage(kDebugSetupShowController,\"Mode was '\"+gMode+\"', overriding device to be 'modeM" ascii
    $s11 = "ix label for 'Slide I/N' display\");var kTapOrSwipeToAdvance=CoreDocs.loc(\"Tap or Swipe to advance\",\"Help string for bottom o" ascii
    $s12 = "tPlaybackReadyHandler:function(a){a()}});" fullword ascii
    $s13 = "er.delegate.setPlaybackReadyHandler(function(){gShowController.startShow()})}function extractDelegateFromUrlParameter(){var d=ge" ascii
    $s14 = "t(\" \");browserVersion=parseFloat(revisionIE[1])}else{browserVersion=11}}browserPrefix=\"ms\"}else{browserPrefix=\"moz\"}}else{" ascii
    $s15 = "se)}else{document.addEventListener(\"load\",setupShowController,false)}}function static_url(a){return a}function setupShowContro" ascii
    $s16 = "cific slide\");var kHelpPlacardShowOrHideKeyboardShortcuts=CoreDocs.loc(\"Show or hide Keyboard Shortcuts\",\"Show or hide Keybo" ascii
    $s17 = "0;var kKeyModifier_Alt=3000;var kKeyModifier_Meta=4000;var kHelpPlacardMainTitle=CoreDocs.loc(\"Keyboard Shortcuts\",\"Keyboard " ascii
    $s18 = "tUrlParameter(\"delegate\");var a;if((d==\"\")||(d==null)||(typeof(d)==\"undefined\")){a=new NullDelegate()}else{var c=d.indexOf" ascii
    $s19 = "rtrait mode on mobile device\");var kOSUnknown=\"unknown\";var kOSWindows=\"Windows\";var kOSMacOSX=\"Mac OS X\";var kOSiOS=\"iO" ascii
    $s20 = "p\")!=-1){debugMessage(kDebugSetupShowController,\"Device was '\"+gDevice+\"', overriding device to be 'deviceDesktop'\");gDevic" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}