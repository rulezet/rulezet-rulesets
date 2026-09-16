rule sig_20150909_472eff9570b6f663be3a95b4d689f2e8 {
  meta:
    description = "datamaliciousorder - file 20150909_472eff9570b6f663be3a95b4d689f2e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23236e68fb210291e4be6c749003846b56d39d16b71b9b71bef59aed04ca0bfc"

  strings:
    $x1  = "var kShowControllerState_Stopped=\"Stopped\";var kShowControllerState_Starting=\"Starting\";var kShowControllerState_Downloading" ascii
    $s2  = "this.queuedUserAction=this.advanceToNextBuild.bind(this,b)}break}return a},advanceToNextSlide:function(d){if(this.script.showMod" ascii
    $s3  = "adEvent);var a=this.promptUserToTryAgain(kUnableToReachiWorkTryAgain);if(a){this.scriptManager.downloadScript()}else{this.displa" ascii
    $s4  = "vanceToNextBuild.bind(this,\"tapNextButton\"))},startShow:function(){this.changeState(kShowControllerState_DownloadingScript);th" ascii
    $s5  = "backController.renderEvent(c)}else{var e=this.script.slideIndexFromSceneIndexLookup[g];var d=this.script.slideList[e];var a=new " ascii
    $s6  = ",b);break;default:debugMessage(kDebugShowController_HandleScriptDidDownloadEvent,\"- hmmm we seem to have arrived here from an u" ascii
    $s7  = ".scriptManager.downloadScript(this.delegate)},exitShow:function(a){clearTimeout(this.exitTimeout);if(a){this.delegate.showExited" ascii
    $s8  = "dNotDownloadEvent.bind(this));document.observe(kStageIsReadyEvent,this.handleStageIsReadyEvent.bind(this));document.observe(kSta" ascii
    $s9  = "(l===\"next\"){if(a===this.script.slideCount-1){if(this.script.loopSlideshow){f=0}else{if(this.delegate.getKPFJsonStringForShow)" ascii
    $s10 = "=this.script.numScenes){if(this.script.loopSlideshow){a=true;this.jumpToScene(0,false)}else{if(this.delegate.getKPFJsonStringFor" ascii
    $s11 = "ptDidDownloadEvent,this.handleScriptDidDownloadEvent.bind(this));document.observe(kScriptDidNotDownloadEvent,this.handleScriptDi" ascii
    $s12 = "processHyperlink:function(k){var d=k.url;var m;if(d.indexOf(\"?slide=\")===0){var l=d.substring(7);var g=-1;if(l===\"first\"){g=" ascii
    $s13 = "onvertDisplayCoOrdsToShowCoOrds(c);if(a.pointX!=-1){d=this.findHyperlinkAtCoOrds(a)}if(d){this.processHyperlink(d)}else{this.adv" ascii
    $s14 = "g=parseInt(d)}else{g=1}h=this.scriptManager.sceneIndexFromSlideIndex(g-1)}if(this.script.recording){if(this.script.recording.eve" ascii
    $s15 = "d.bind(this,c)}break}},goBackToPreviousSlide:function(c){if(this.script.showMode==kShowModeHyperlinksOnly){return}if(this.displa" ascii
    $s16 = "State(null,\"Keynote\",a[0]+\"#\"+c+(b[1]?\"?\"+b[1]:\"\"))}},startSoundTrack:function(){if(gMode===kModeMobile){return}if(this." ascii
    $s17 = "KPFEvent({slideId:d,slideIndex:e,sceneIndex:g,event:this.script.events[g],animationSupported:this.animationSupported});this.play" ascii
    $s18 = "Build:function(b){if(this.script.showMode===kShowModeHyperlinksOnly&&b!=\"currentSceneDidComplete\"){return false}if(this.displa" ascii
    $s19 = "his.exitShow()}}}else{f=a+1}}else{if(l===\"previous\"){if(a===0){if(this.script.loopSlideshow){f=this.script.slideCount-1}else{f" ascii
    $s20 = "this.script.lastSceneIndex){break}var e=this.script.events[h];var b=e.automaticPlay==1||e.automaticPlay==true;this.jumpToScene(h" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}